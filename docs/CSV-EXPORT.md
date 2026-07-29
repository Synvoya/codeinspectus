# CSV export

CSV is a deterministic spreadsheet projection of the same normalized, redacted V2 JSON export:

```bash
codeinspectus scan . --format csv --output findings.csv
codeinspectus export SCAN_ID --format csv --output findings.csv
```

The file is UTF-8 RFC 4180 CSV with CRLF record endings and every cell quoted. It always contains
one `scan` row followed by zero or more `finding` rows sorted by finding ID, fingerprint, file and
line. The scan row preserves aggregate coverage and the complete coverage-evidence array even when
there are no findings. A partial or unknown scan therefore cannot become an empty, apparently clean
spreadsheet.

## Version 1.0.0 columns

The header order is part of the public contract:

```text
record_type,csv_schema_version,scan_id,target,started_at,duration_ms,aggregate_coverage,coverage_evidence_json,policy_mode,finding_id,fingerprint,title,severity,confidence,engine,engines_json,producer_components_json,rule_id,vulnerability_aliases_json,cwes_json,owasp_web_json,owasp_api_json,owasp_llm_json,attack_techniques_json,file,start_line,end_line,snippet,message,remediation_summary,remediation_steps_json,remediation_code_suggestion,remediation_references_json,frameworks_json,is_secret,secret_value_hash,finding_kind,scope_role,baseline_state,triage_context_json
```

`record_type=scan` carries scan and coverage metadata. `record_type=finding` carries the normalized
fields for exactly one canonical JSON finding plus the same aggregate coverage status. Array/object columns use compact
JSON so producer provenance, coverage evidence, remediation, framework and triage structures are
not lossy. `baseline_state` is populated only when the normalized export contains a baseline item.

CSV findings have one-to-one identity parity with the JSON export; CSV does not apply the display
severity or maximum-findings projection. Raw secret values are redacted by the normalized export
model before CSV encoding.

To prevent spreadsheet formula execution, any string whose first non-whitespace character is
`=`, `+`, `-` or `@`, or which begins with a tab/newline control, is prefixed with a literal
apostrophe before RFC 4180 quoting. Consumers that need byte-exact source text should use JSON,
not remove this safety prefix automatically.

Exact-file and output-directory writes use the same containment checks and atomic replacement
contract as JSON and SARIF. Naming an exact `--output` file is explicit approval for that artifact;
directory output still requires the established repository-containment approval.
