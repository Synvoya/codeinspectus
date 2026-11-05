# Synvoya Node.js ruleset (`syn-node-*`) — license & provenance

**License:** Apache-2.0 (same as CodeInspectus). © Synvoya.

**Authorship.** These Opengrep rules were written for CodeInspectus 4.0 (milestone M3, 2026-11-04)
from first principles: the API documentation of the libraries they name (Node.js `child_process`,
`fs` and `vm`; Express; Next.js; NestJS; jsonwebtoken; knex; Prisma; Sequelize; TypeORM; adm-zip,
unzipper, yauzl and JSZip; js-yaml; funcster; cryo; H3; Hono) and the CWE entries in each rule's
metadata.
No rule, message, pattern or test file from `semgrep/semgrep-rules` (Semgrep Rules License v1.0)
or `opengrep/opengrep-rules` (LGPL-2.1 + Commons Clause) was opened, copied or adapted while
writing them (legal gate CG-63). Where a pattern resembles another tool's, it is because the API
call itself (`res.redirect(x)`, `vm.runInNewContext(code)`) is the only way to express the check.

**How the rules are built.** Injection, path, zip-slip, prototype-key and JWT-decode rules use
Opengrep taint mode with a request-input source block written for this pack and sanitizers chosen
by us (numeric casts, `path.basename`, bound-parameter and tagged-template SQL, containment and
allow-list checks treated as by-side-effect sanitizers). Request sources cover Express, Koa and
Fastify request objects; Next.js route handlers (including `(await request.json()) as T`
destructuring) and server actions; NestJS `@Body/@Query/@Param/@Headers`; H3/Nuxt `readBody`,
`readFormData`, `getQuery`, `getRouterParam(s)`; Hono `c.req.*`. Other frameworks are not sources.
Configuration rules are structural; `syn-node-placeholder-secret-deploy` is a regex rule over
deploy files. Each sink excludes only the `ci-baseline-*` rule's own patterns, and a baseline TP
fixture proves the baseline fires on every excluded shape, so a line never gets two findings for one
weakness and no shape is dropped on an untested assumption (eval E112 checks no line carries both).
The experimental `syn-node-sql-injection` faces a taint-mode baseline, so it copies the baseline's
sources under a `BASE` label: on the baseline's own sink shapes it reports only input that `BASE` does
not reach. Rule `paths` use file-basename globs
only: Opengrep matches them against the absolute path, so a folder name could match a parent folder
of the scanned project and silently switch a rule off (eval E111).

**Precision gate (design §4.5, PRD §9.2).** Every rule has TP and FP fixtures under
`fixtures/synvoya-node-corpus/<rule-id>/` (eval E110). Every field hit was triaged by the authoring
agent, with the table kept in the maintainers' private triage record, for
re-triage by an independent reviewer agent. Rules that failed the gate are kept out of this
folder, in `opengrep-rules-experimental/synvoya-node-experimental/` at the repository root, which is
neither loaded by the scanner nor shipped in the npm package.

**Holdout gate (4.0 final field run, 2026-11-05).** The pack had scored 24/24 TP together with the PHP
pack on the repositories it was tuned on. Re-measured on 12 holdout repositories it was never tuned
on (gate: false positives at most 1 in 5 of a rule's holdout hits), `syn-node-sql-injection` (103 hits,
11 TP) and `syn-node-path-traversal` (22 hits, 0 TP) failed and moved to the experimental folder for
4.1, to be fixed and re-measured on a new holdout set. `syn-node-jwt-verify-no-algorithms` (5 hits,
all TP-low) and `syn-node-trust-proxy-unconditional` (1 hit, TP-low) passed. The other rules had no
holdout hit; they ship because they had no tuning-repository false positive and their fixtures pass.

Every rule carries `metadata.cwe` and `metadata.confidence`. Files are plain local YAML; no
scan-time fetch. Keep all files ASCII-only (Opengrep reads rule files as ASCII).
