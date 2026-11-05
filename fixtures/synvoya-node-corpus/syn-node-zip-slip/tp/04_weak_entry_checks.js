const AdmZip = require("adm-zip");
const fs = require("fs");
const path = require("path");
// A logged check, a ".." deny check (absolute entry names have no "..") and an unanchored regex
// do not keep an entry inside the destination.
module.exports = function unpack(file, dest) {
  const zip = new AdmZip(file);
  for (const entry of zip.getEntries()) {
    const target = path.join(dest, entry.entryName);
    console.log("inside:", target.startsWith(dest));
    fs.writeFileSync(target, entry.getData());
  }
  for (const entry of zip.getEntries()) {
    const name = entry.entryName;
    if (name.includes("..")) continue;
    fs.writeFileSync(name, entry.getData());
  }
  for (const entry of zip.getEntries()) {
    const name = entry.entryName;
    if (!/\.txt$/.test(name)) continue;
    fs.writeFileSync(path.join(dest, name), entry.getData());
  }
};
