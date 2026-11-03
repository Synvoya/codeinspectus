import fs from "fs";
export function h(name: string) {
  return fs.readFileSync(baseDir + name);
}
