import fs from "fs";
export function h(req: any) {
  return fs.readFileSync(String(req.params.f) + ".md");
}
