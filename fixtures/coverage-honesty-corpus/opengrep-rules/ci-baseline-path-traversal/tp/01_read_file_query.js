const fs = require("fs");
export function h(req, res) {
  fs.readFile(req.query.file + ".txt", (error, data) => res.send(data));
}
