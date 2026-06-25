// FIXTURE — planted issue #3: SQL injection sink (string-built query).
// Detected by: Opengrep security-baseline rule ci-baseline-sql-injection-string-build.
// CWE-89; OWASP A03:2021. (Generic SAST = the engine's job, not the AI moat.)
import { Pool } from "pg";

const pool = new Pool();

export async function getUserById(req: { params: { id: string } }) {
  const id = req.params.id;
  // Unsafe: user input concatenated directly into SQL.
  return pool.query("SELECT * FROM users WHERE id = '" + id + "'");
}

export async function safeGetUserById(req: { params: { id: string } }) {
  // Safe equivalent (parameterized) — should NOT be flagged (precision check).
  return pool.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
}
