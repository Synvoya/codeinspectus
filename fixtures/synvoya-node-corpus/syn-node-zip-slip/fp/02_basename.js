const fs = require("fs");
const path = require("path");
module.exports = function unpack(parser, dest) {
  parser.on("entry", (entry) => {
    entry.pipe(fs.createWriteStream(path.join(dest, path.basename(entry.path))));
  });
};
