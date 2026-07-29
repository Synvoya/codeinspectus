# Git-scoped scans

CodeInspectus can inspect an exact commit range or the current working tree while retaining
the repository context needed by technology, framework, authorization, configuration,
dependency, workflow-chain, and cross-file analysis.

```bash
codeinspectus scan . --diff origin/main --head HEAD
codeinspectus scan . --working-tree --base HEAD
```

Both forms are read-only. They run only Git plumbing commands and never checkout, reset,
stage, commit, create a worktree, or modify source. Commit mode resolves both revisions to
full commit IDs and materializes the exact head tree in a bounded OS temporary directory.
Only the final scan record uses managed CodeInspectus storage; the temporary snapshot scan
is not persisted.

## Scope contract

JSON, SARIF, stored history, and text output identify:

- the requested and resolved base/head commits;
- added, modified, deleted, renamed, untracked, and ignored paths;
- binary, generated/build, and submodule state as independent flags;
- whether each path was inspected;
- primary changed paths versus findings retained from supporting repository context;
- separate primary and supporting-context finding counts;
- `complete` or `partial` scope plus explicit limitations.

Deleted content is not scanned; the resulting tree and supporting context are. Ignored paths
are enumerated as excluded metadata. Binary content, generated/build artifacts, symbolic
links, and submodule contents are not presented as inspected source. A gap in required
context, bounded enumeration, or any such uninspected changed surface makes Git scope
`partial`, and CI returns exit code 2 rather than treating it as clean.

Working-tree mode compares the resolved base against the combined index and filesystem,
then adds non-ignored untracked files. It scans the current repository in place without
writing it. Commit mode scans the exact resolved head snapshot, so later branch movement
cannot change what was inspected.

Severity enforcement applies to `primary` findings. Supporting-context findings remain in
the raw JSON/SARIF/history record for review but do not make an unrelated change fail the
threshold. Incomplete Git or scanner coverage still takes precedence and returns exit code 2.
