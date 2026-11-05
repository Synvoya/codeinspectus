import { promisify } from "node:util";
import { exec } from "node:child_process";
const sh = promisify(exec);
export async function log(req: any) {
  return sh(`git log --oneline ${req.query.ref}`);
}
