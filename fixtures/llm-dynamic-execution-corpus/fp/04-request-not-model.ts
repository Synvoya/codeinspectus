import { exec } from "node:child_process";

export function run(req: any) {
  exec(req.query.command);
}
