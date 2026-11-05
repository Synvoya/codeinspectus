const AdmZip = require("adm-zip");
const fs = require("fs");
const path = require("path");
module.exports = function unpack(file, dest) {
  const zip = new AdmZip(file);
  for (const entry of zip.getEntries()) {
    const target = path.join(dest, entry.entryName);
    if (!path.resolve(target).startsWith(path.resolve(dest) + path.sep)) continue;
    fs.writeFileSync(target, entry.getData());
  }
};
