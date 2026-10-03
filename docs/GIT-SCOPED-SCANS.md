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

- the requested base and the resolved diff base (the merge-base of base and head, so changes made
  only on the base branch are not attributed to the change) and head commits;
- added, modified, deleted, renamed, untracked, and ignored paths;
- binary, generated/build, and submodule state as independent flags;
- whether each path was inspected;
- primary changed paths versus findings retained from supporting repository context;
- separate primary and supporting-context finding counts;
- `complete` or `partial` scope plus explicit limitations.

Deleted content is not scanned; the resulting tree and supporting context are. Ignored paths
are enumerated as excluded metadata. Binary content, generated/build artifacts, symbolic
links, and submodule contents are not presented as inspected source. A gap in required
context or any such uninspected changed surface makes Git scope `partial`, and CI returns exit
code 2 rather than treating it as clean. A change set or tree beyond the 50,000-entry enumeration
limit stops the scan with an error (also exit code 2) instead of reporting a partial result.

Working-tree mode compares the resolved base against the combined index and filesystem,
then adds non-ignored untracked files. Index entries flagged `skip-worktree` or
`assume-unchanged` whose content differs, and files removed with `git rm --cached` that are still
on disk (even if now ignored), are also in scope because git would otherwise hide those edits. It scans the current repository in place without
writing it. Commit mode scans the exact resolved head snapshot, so later branch movement
cannot change what was inspected.

Severity enforcement applies to `primary` findings. A change can also introduce a finding in an
unchanged file (for example by deleting the migration that enabled row-level security), so the
diff base is scanned too: any supporting-context finding that is not present in the base is new
and treated as `primary`. Supporting-context findings that already existed remain in the raw
JSON/SARIF/history record for review but do not make an unrelated change fail the threshold.
Submodule pointer changes are reported even when `.gitmodules` sets `ignore = all`. Incomplete Git or scanner coverage still takes precedence and returns exit code 2.
