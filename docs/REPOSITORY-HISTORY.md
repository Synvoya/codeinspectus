# Bounded repository-history scanning

Repository-history scanning is disabled unless every scope boundary is explicit:

```bash
codeinspectus history scan /path/to/repository \
  --from v1.0.0 --to HEAD \
  --since 2026-01-01T00:00:00Z --until 2026-07-30T00:00:00Z \
  --max-commits 20 --format json
```

`--from` must be an ancestor of `--to`. Both resolve to immutable full commit IDs before scanning.
The two UTC timestamps are inclusive and `--max-commits` is required (1–50). When more commits
match, CodeInspectus scans only the newest bounded window, includes the selected head, reports
truncation, returns aggregate `partial`, and exits 2. Shallow repositories also remain partial.

Each selected commit is materialized into a bounded OS temporary directory using read-only Git
plumbing. The repository is never checked out, reset, staged, committed or written. Commit trees
are bounded by the same 50,000-entry, 128 MiB total and 8 MiB-per-blob limits used by exact diff
scans. Symlinks and submodule gitlinks are not materialized and make that snapshot partial.

Every successful snapshot produces a normal persisted CodeInspectus scan and scan ID. Its ordinary
JSON/SARIF/CSV export remains available through `codeinspectus export`. The scan metadata records the
exact commit, timestamp, snapshot completeness and whether it is `historical` or the explicitly
selected head. The separate manifest stores only counts, coverage, change metadata and scan IDs—not
finding messages or secret material.

Change metadata compares a merge commit to its first parent. Added, modified, renamed and deleted
paths are recorded; deleted content is represented only as historical metadata. A finding in an old
snapshot does not prove that a vulnerability or credential remains active in the selected head or a
deployed system. CodeInspectus never performs live secret verification.

The manifest defaults to `~/.codeinspectus/repository-history/`. An explicit `--manifest` must be a
new file outside the scanned repository and is written atomically. Failed, cancelled or unknown
commit scans make aggregate coverage `unknown`; shallow, truncated, change-metadata-limited or
partially scanned snapshots make it `partial`. Only a complete bounded request returns exit 0.
