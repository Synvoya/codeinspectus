import { exec, execSync } from "node:child_process";
export function convert(req: any, done: () => void) {
  const command = `convert ${req.body.input} out.png`;
  exec(command, done);
  return execSync("du -sh " + req.params.dir, { encoding: "utf8" });
}
