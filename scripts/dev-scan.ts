/** Dev harness: run runScan() directly against a path and print findings. */
import { runScan } from "../src/scan.js";

const path = process.argv[2] ?? "fixtures/vulnerable-app";
const scanners = process.argv[3] ? (process.argv[3].split(",") as never[]) : undefined;

const r = await runScan({ path, scanners, include_compliance: true });

process.stderr.write(`\nscan_id=${r.scan_id}\n`);
process.stderr.write(`summary=${JSON.stringify(r.summary)}\n`);
process.stderr.write(`engines_run=${JSON.stringify(r.engines_run)}\n`);
process.stderr.write(`trivy_db_date=${r.trivy_db_date ?? "(none)"}\n\n`);
for (const e of r.engine_details) {
  process.stderr.write(`  engine ${e.engine}@${e.version} ran=${e.ran} count=${e.finding_count}${e.note ? " note=" + e.note.slice(0, 120) : ""}\n`);
}
process.stderr.write(`\nFINDINGS (${r.findings.length}):\n`);
for (const f of r.findings) {
  process.stderr.write(
    `  ${f.id} [${f.severity}] ${f.rule_id} :: ${f.location.file}:${f.location.start_line} :: ${f.engine}(${f.engines.join("+")}) :: ${f.cwe.join(",")} :: ${f.title}\n`,
  );
}
process.stderr.write(`\ncompliance_overview=${JSON.stringify(r.compliance_overview, null, 2)}\n`);
