const unzipper = require("unzipper");
const fs = require("fs");
const path = require("path");
module.exports = function unpack(stream, dest) {
  stream.pipe(unzipper.Parse()).on("entry", (entry) => {
    const target = path.join(dest, entry.path);
    entry.pipe(fs.createWriteStream(target));
  });
};
