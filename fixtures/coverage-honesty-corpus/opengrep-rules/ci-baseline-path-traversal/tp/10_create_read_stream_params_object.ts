import fs from "fs";
export function h(req: any) {
  return fs.createReadStream(req.params + ".csv");
}
