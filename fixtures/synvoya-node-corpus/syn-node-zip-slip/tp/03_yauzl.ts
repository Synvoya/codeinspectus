import * as fs from "fs";
import * as path from "path";
export function unpack(zipfile: any, dest: string) {
  zipfile.on("entry", (entry: any) => {
    const target = path.resolve(dest, entry.fileName);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    zipfile.openReadStream(entry, (err: any, rs: any) => rs.pipe(fs.createWriteStream(target)));
  });
}
