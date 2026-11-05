import fs from "fs";
export function h(req: any, cb: any) {
  // Known gap: template-literal paths are not matched by this rule.
  fs.readFile(`${req.query.file}`, cb);
}
