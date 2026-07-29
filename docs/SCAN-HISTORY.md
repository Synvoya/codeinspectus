# Scan history and comparison

CodeInspectus stores canonical scan records locally under `~/.codeinspectus/scans/`. The history
commands inspect that managed store; they do not modify the scanned repository and make no network
requests.

```bash
codeinspectus scans list
codeinspectus scans show SCAN_ID
codeinspectus scans rerun SCAN_ID
codeinspectus scans compare OLD_SCAN_ID NEW_SCAN_ID
```

Add `--format json` to any command for machine-readable output. `show --format json` uses the
versioned CodeInspectus export schema and applies the normal secret-redaction rules. Comparison and
rerun JSON redact findings through the same output projection.

## Listing and filters

`scans list` is newest-first, with scan ID as the deterministic tie-breaker. It returns at most 50
records by default and accepts `--limit 1..200`.

```bash
codeinspectus scans list --repository /work/project --status findings
codeinspectus scans list --path /work/project/src/auth.ts --severity high
codeinspectus scans list --since 2026-07-01 --until 2026-07-31 --format json
```

- `--repository` is an exact canonical Git-root match. A legacy record without a recorded Git root
  uses its exact scan target as the fallback identity.
- `--path` matches scans whose target contains the path, scans of an ancestor of the path, or a
  recorded finding at that repository-relative location.
- `--since` and `--until` are inclusive. `YYYY-MM-DD` means the start or end of that UTC day;
  timestamps must include `Z` or an explicit offset.
- `--severity` matches a scan containing at least one finding at or above `critical`, `high`,
  `medium`, `low`, or `info`.
- `--status` accepts `clean`, `findings`, `partial`, or `unknown`. `clean` is possible only when
  aggregate coverage is complete. Missing or uncertain coverage is never labelled clean.

Store reads are capped at 5,000 lexicographically selected JSON files, 8 MiB per record, and 64 MiB
in total; corruption details are capped at 100. The output reports the file, byte, and result bounds.
Oversized records are isolated without reading their contents. When the total byte budget is
exhausted, the remaining deterministic subset is omitted and counted. If any bound is exceeded, the
store is unavailable, or records are corrupt, foreign, malformed, or non-regular, valid records are
still returned but the result is explicitly partial and the command exits `2`. A bounded subset is
never described as the global latest history.

## Comparison semantics

`scans compare` requires two distinct scan IDs for the same canonical target, ordered oldest to
newest. `scans rerun` runs the original target again with its recorded scanner scope and finding
limit, then performs the same comparison.

Each finding has one state:

- `Persisting`: the finding exists in both scans by fingerprint or stable deduplication identity.
- `Resolved`: the finding is absent from the new scan, both scans have complete canonical
  whole-product coverage, every producer ran, and producer-component signatures are compatible.
- `New`: the finding is absent from the old scan under compatible like-for-like producer coverage,
  and does not occur in the complete bounded earlier history.
- `Reopened`: a three-point history proves that the same finding occurred before the old scan, was
  provably resolved by the old scan, and exists again in the new scan.
- `Not rechecked / unknown`: the available evidence cannot prove one of the states above.

Absence alone never proves resolution. Changed checks, missing producer metadata, excluded or
failed engines, truncation, legacy non-canonical records, corrupt history, or a bounded-out history
store all degrade affected claims to `Not rechecked / unknown`. V1.x records remain loadable, but
missing V2 provenance is treated as uncertainty rather than invented evidence.

## Failure and safety contract

Malformed and traversal-shaped IDs are rejected before file access. The loader accepts only regular
managed files whose filename and embedded scan ID agree; symlinks, foreign records, and invalid JSON
are rejected or isolated. History commands return `0` only for a complete requested result and `2`
for usage errors, unavailable/corrupt/bounded history, or comparisons containing unknown states.
