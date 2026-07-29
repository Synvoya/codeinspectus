# Bounded local bulk scanning

Scan Git repositories that already exist as immediate children of one explicit local parent:

```bash
codeinspectus bulk scan /absolute/path/to/repositories --format json
codeinspectus bulk scan /absolute/path/to/repositories \
  --manifest /outside/repositories/team-scan.json \
  --concurrency 2 --max-repositories 50
```

Bulk mode never authenticates to GitHub, discovers an organization, clones, fetches, checks out or
deletes repositories. Split larger trees into explicit parents. Only immediate non-symbolic child
directories with a regular `.git` directory/file are candidates; discovery is deterministic by
canonical path.

## Bounds and isolation

- Parent entries: hard fail-closed discovery bound of 10,000.
- Selected repositories: 1–500, default 50.
- Concurrent repositories: 1–8, default 2. Each repository scan can already run multiple engines,
  so higher bulk concurrency is deliberately capped.
- Attempts per repository: 1–5, default 2; retries happen only when the same manifest is resumed.
- Manifest size: 2 MiB.

Each repository invokes the normal scanner independently and receives its own scan ID, coverage,
history record, target containment and engine cleanup. The manifest contains repository paths,
scan IDs, coverage, counts, timestamps and redacted errors—never finding titles, messages,
snippets or remediation. Full findings remain isolated in their normal per-scan records.

The aggregate result is `complete` only when discovery is complete and every selected repository
has complete aggregate coverage. A bounded-out repository or any partial child makes it `partial`.
Pending, running, unknown, failed, cancelled or zero selected repositories make it `unknown`.
Partial/unknown output exits 2.

## Resuming safely

Without `--manifest`, CodeInspectus creates a versioned manifest under its managed local directory
and prints the path. With `--manifest`, the parent directory must already exist and the file must be
outside the repository parent tree. Re-run the exact command with that same file to resume.

Resume requires the same canonical parent and exact scan/bound configuration. Completed entries are
not scanned again. Failed, interrupted or cancelled entries return to pending only while below the
attempt bound. Writes are atomic and schema-validated after every state transition. A corrupt,
symbolic, foreign-parent, out-of-scope or configuration-mismatched manifest fails closed.

SIGINT/SIGTERM stop active external engines, allow in-flight workers to record completion or
cancellation, leave unstarted work pending, persist the manifest, and return 130/143. CodeInspectus
creates no clone or bulk scratch tree to clean up; normal per-scan temporary artifacts retain their
existing bounded cleanup.

A bulk run is not an atomic snapshot across repositories. Each entry records its own scan time; a
long or resumed run may therefore represent repositories at different working-tree moments. Use
pinned detached local checkouts when a cross-repository immutable evidence set is required.
