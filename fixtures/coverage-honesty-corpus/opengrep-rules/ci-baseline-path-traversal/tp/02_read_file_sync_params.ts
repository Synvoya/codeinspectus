import fs from "fs";
export function h(req: any) {
  return fs.readFileSync(req.params.name + "");
}
