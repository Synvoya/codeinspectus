const AdmZip = require("adm-zip");
const fs = require("fs");
const path = require("path");
module.exports = function unpack(file, dest) {
  const zip = new AdmZip(file);
  for (const entry of zip.getEntries()) {
    const out = path.join(dest, entry.entryName);
    fs.writeFileSync(out, entry.getData());
  }
};
