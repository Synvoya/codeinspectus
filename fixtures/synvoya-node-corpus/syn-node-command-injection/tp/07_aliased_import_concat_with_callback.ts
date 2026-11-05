import { exec as run } from "child_process";
export function list(req: any, done: () => void) {
  run("ls " + req.query.dir, done);
}
