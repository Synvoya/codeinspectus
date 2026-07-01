# How this repository is built

CodeInspectus is a local-first security MCP server. This page explains how the public
repository is produced and how to build it yourself. If you want to contribute — or just
audit how the project is assembled before trusting it — this is the context you need.

## An allow-list, auditable repository

This repository is assembled by an **automated, allow-list release process, not hand-curated** file
by file: only **git-tracked files** are published. Anything not committed (local notes, scratch
files, build output) **cannot** appear here, even by accident. This repository is the complete,
runnable tool — there is nothing you need that lives somewhere else.

Why that matters for a security tool:

- **Auditable.** What ships is exactly the git-tracked files of a tagged commit, minus a short,
  documented set of exclusions (below). There are no hidden, file-by-file hand edits.
- **Reproducible.** Re-running the release process at the same commit produces the same tree —
  what you see is what was committed.
- **Leak-resistant by construction.** Because the export is allow-list (tracked-only) rather
  than deny-list (copy-everything-then-strip), an untracked file can't slip through: there is
  nothing to forget to remove.

## What ships here vs. what stays internal

**This repository contains everything a user or contributor needs:**

- the runtime (`src/**`) and the build/release configuration,
- the detection database (`detection-db/**`) and the compliance mapping data (`data/**`),
- the agent-integration rules (`agent-rules/**`),
- the transparency and provenance documents (`docs/**`),
- the test suite, the evaluation suite, the fixtures (true- and false-positive samples), and the
  contributor scripts.

**A small amount of internal-only maintainer material is deliberately kept out of this repository:**

- maintainer engineering notes — debugging logs that record *how* a particular bug was chased,
  not *what* the shipped code does,
- internal fixture-expectation bookkeeping that only duplicates what the fixtures themselves and
  [`CONTRIBUTING.md`](../CONTRIBUTING.md) already make clear,
- the export tooling itself, which encodes maintainer-only workflow assumptions.

None of the excluded material is needed to build, run, test, or contribute to CodeInspectus. If
you ever find you need something that isn't here, that is a gap worth an issue.

## Building it yourself

From a fresh clone:

```bash
npm install
npm run build          # tsc --noEmit && tsup — must compile clean
npm test               # unit + integration tests (vitest)
npm run eval           # the eval suite against fixtures/vulnerable-app
npm run test:redaction # end-to-end check that no secret value leaks into tool output
```

- The scanning engines (Opengrep, Gitleaks, Trivy) are **external, SHA-pinned binaries**, not npm
  packages. Some engine-dependent evals skip until those binaries are installed — that is expected,
  not a failure.
- For the full verification checklist — including how to confirm **zero network egress at scan
  time** — see [`docs/context/verify.md`](context/verify.md).
- For the contribution workflow (fork → branch → PR, the precision bar for new detection rules, and
  the compliance honesty metric), see [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Scope of this page

This describes the **principle** — an allow-list export plus a short, documented set of exclusions —
not an internal build mechanism. The exact release tooling and internal workflow are intentionally
not published; they carry no value to a user and would only add noise. The guarantees that matter to
you hold regardless: tracked-only export, no hidden edits, and everything needed to build, test, and
contribute is present in this repository.
