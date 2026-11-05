const AdmZip = require("adm-zip");
const fs = require("fs");
const path = require("path");
module.exports = function unpack(file, dest) {
  const root = path.resolve(dest);
  const zip = new AdmZip(file);
  for (const entry of zip.getEntries()) {
    const out = path.resolve(root, entry.entryName);
    if (!out.startsWith(root + path.sep)) continue;
    fs.writeFileSync(out, entry.getData());
  }
  zip.extractAllTo(dest, true);
};
